package image

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/image/copy"
	"github.com/containers/image/signature"
	"github.com/containers/image/transports/alltransports"
	"github.com/docker/distribution/reference"
	"github.com/pkg/errors"
	"github.com/replicatedhq/kots/pkg/logger"
	"gopkg.in/yaml.v2"
)

var imagePolicy = []byte(`{
  "default": [{"type": "insecureAcceptAnything"}]
}`)

type k8sYAML struct {
	Spec k8sSpec `yaml:"spec"`
}

type k8sSpec struct {
	Template k8sTemplate `yaml:"template"`
}

type k8sTemplate struct {
	Spec k8sPodSpec `yaml:"spec"`
}

type k8sPodSpec struct {
	Containers []k8sContainer `yaml:"containers"`
}

type k8sContainer struct {
	Image string `yaml:"image"`
}

type ImageRef struct {
	Domain string
	Name   string
	Tag    string
	Digest string
}

type RegistryAuth struct {
	Username string
	Password string
}

func SaveImages(log *logger.Logger, imagesDir string, upstreamDir string) error {
	savedImages := make(map[string]bool)

	err := filepath.Walk(upstreamDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			contents, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			err = extractImagesFromFile(log, imagesDir, contents, savedImages)
			if err != nil {
				return errors.Wrap(err, "failed to extract images")
			}

			return nil
		})

	if err != nil {
		return errors.Wrap(err, "failed to walk upstream dir")
	}

	return nil
}

func GetImages(upstreamDir string) ([]string, error) {
	uniqueImages := make(map[string]bool)

	err := filepath.Walk(upstreamDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			contents, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			images := listImagesInFile(contents)
			for _, image := range images {
				uniqueImages[image] = true
			}
			return nil
		})

	if err != nil {
		return nil, errors.Wrap(err, "failed to walk upstream dir")
	}

	result := make([]string, 0, len(uniqueImages))
	for i := range uniqueImages {
		result = append(result, i)
	}

	return result, nil
}

func extractImagesFromFile(log *logger.Logger, imagesDir string, fileData []byte, savedImages map[string]bool) error {
	images := listImagesInFile(fileData)
	for _, image := range images {
		if _, saved := savedImages[image]; saved {
			continue
		}

		log.ChildActionWithSpinner("Pulling image %s", image)
		err := saveOneImage(imagesDir, image)
		if err != nil {
			log.FinishChildSpinner()
			return errors.Wrap(err, "failed to save image")
		}

		log.FinishChildSpinner()
		savedImages[image] = true
	}

	return nil
}

func listImagesInFile(contents []byte) []string {
	images := make([]string, 0)

	yamlDocs := bytes.Split(contents, []byte("\n---\n"))
	for _, yamlDoc := range yamlDocs {
		parsed := &k8sYAML{}
		if err := yaml.Unmarshal(yamlDoc, parsed); err != nil {
			continue
		}

		for _, container := range parsed.Spec.Template.Spec.Containers {
			images = append(images, container.Image)
		}
	}

	return images
}

func saveOneImage(imagesDir string, image string) error {
	imageRef, err := imageRefImage(image)
	if err != nil {
		return errors.Wrap(err, "failed to parse image ref")
	}

	imageFormat := "docker-archive"
	pathInBundle := imageRef.pathInBundle(imageFormat)
	archiveName := filepath.Join(imagesDir, pathInBundle)
	destDir := filepath.Dir(archiveName)

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return errors.Wrap(err, "failed to create destination dir")
	}

	policy, err := signature.NewPolicyFromBytes(imagePolicy)
	if err != nil {
		return errors.Wrap(err, "failed to read default policy")
	}
	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		return errors.Wrap(err, "failed to create policy")
	}

	srcRef, err := alltransports.ParseImageName(fmt.Sprintf("docker://%s", image))
	if err != nil {
		return errors.Wrap(err, "failed to parse source image name")
	}

	destStr := fmt.Sprintf("%s:%s", imageFormat, archiveName)
	destRef, err := alltransports.ParseImageName(destStr)
	if err != nil {
		return errors.Wrapf(err, "failed to parse local image name: %s", destStr)
	}

	_, err = copy.Image(context.Background(), policyContext, destRef, srcRef, &copy.Options{
		RemoveSignatures:      true,
		SignBy:                "",
		ReportWriter:          nil,
		SourceCtx:             nil,
		DestinationCtx:        nil,
		ForceManifestMIMEType: "",
	})
	if err != nil {
		return errors.Wrap(err, "failed to copy image")
	}

	return nil
}

func imageRefImage(image string) (*ImageRef, error) {
	ref := &ImageRef{}

	// named, err := reference.ParseNormalizedNamed(image)
	parsed, err := reference.ParseAnyReference(image)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse image name %q", image)
	}

	if named, ok := parsed.(reference.Named); ok {
		ref.Domain = reference.Domain(named)
		ref.Name = named.Name()
	} else {
		return nil, errors.New(fmt.Sprintf("unsupported ref type: %T", parsed))
	}

	if tagged, ok := parsed.(reference.Tagged); ok {
		ref.Tag = tagged.Tag()
	} else if can, ok := parsed.(reference.Canonical); ok {
		ref.Digest = can.Digest().String()
	} else {
		ref.Tag = "latest"
	}

	return ref, nil
}

func (ref *ImageRef) pathInBundle(formatPrefix string) string {
	path := []string{formatPrefix, ref.Name}
	if ref.Tag != "" {
		path = append(path, ref.Tag)
	}
	if ref.Digest != "" {
		digestParts := strings.Split(ref.Digest, ":")
		path = append(path, digestParts...)
	}
	return filepath.Join(path...)
}

func CopyFromFileToRegistry(path string, name string, tag string, digest string) error {
	policy, err := signature.NewPolicyFromBytes(imagePolicy)
	if err != nil {
		return errors.Wrap(err, "failed to read default policy")
	}
	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		return errors.Wrap(err, "failed to create policy")
	}

	srcRef, err := alltransports.ParseImageName(fmt.Sprintf("docker-archive:%s", path))
	if err != nil {
		return errors.Wrap(err, "failed to parse src image name")
	}

	destStr := fmt.Sprintf("docker://%s:%s", name, tag)
	destRef, err := alltransports.ParseImageName(destStr)
	if err != nil {
		return errors.Wrapf(err, "failed to parse dest image name: %s", destStr)
	}

	_, err = copy.Image(context.Background(), policyContext, destRef, srcRef, &copy.Options{
		RemoveSignatures:      true,
		SignBy:                "",
		ReportWriter:          nil,
		SourceCtx:             nil,
		DestinationCtx:        nil,
		ForceManifestMIMEType: "",
	})
	if err != nil {
		return errors.Wrap(err, "failed to copy image")
	}

	return nil
}
